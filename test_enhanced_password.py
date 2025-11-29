#!/usr/bin/env python3
"""Test script for enhanced password strength analysis"""

import os
import sys
import json
sys.path.insert(0, os.path.dirname(__file__))

from security_modules.password_generator import PasswordGenerator

def test_enhanced_analysis():
    """Test the enhanced password strength analysis functionality"""
    pg = PasswordGenerator()
    
    # Test passwords with different characteristics
    test_cases = [
        ("Test@Pass123!", "Good mixed password"),
        ("password123", "Weak common password"),
        ("P@ssW0rd!2024", "Strong with year pattern"),
        ("MySecret!Password#2024", "Very strong passphrase"),
        ("aaaa1111", "Weak with repetition"),
        ("Tr0ub4dor&3", "Strong classic example")
    ]
    
    print("Enhanced Password Strength Analysis Test")
    print("=" * 60)
    
    for password, description in test_cases:
        print(f"\nTesting: {description}")
        print(f"Password: {password}")
        print("-" * 40)
        
        try:
            result = pg.calculate_strength(password)
            
            print(f"Score: {result['score']}/100")
            print(f"Level: {result['level']}")
            print(f"Entropy: {result['entropy']} bits")
            print(f"Character Set Size: {result['charset_size']}")
            
            # Show character analysis
            char_analysis = result['character_analysis']
            print("Character Types:", end=" ")
            types = [k for k, v in char_analysis.items() if v]
            print(", ".join(types))
            
            # Show security rating
            rating = result['security_rating']
            print(f"Rating: {rating['rating']} - {rating['description']}")
            
            # Show first few warnings
            if result['warnings']:
                print("Key Warnings:")
                for warning in result['warnings'][:2]:
                    print(f"  - {warning}")
            
            # Show first few suggestions
            if result['improvement_suggestions']:
                print("Suggestions:")
                for suggestion in result['improvement_suggestions'][:2]:
                    print(f"  - {suggestion}")
                    
            # Show crack time estimates
            crack_time = result['crack_time']
            print(f"Crack Time (Online): {crack_time['online']}")
            print(f"Crack Time (Offline Fast): {crack_time['offline_fast']}")
            
        except Exception as e:
            print(f"ERROR: {e}")
            print(f"Type: {type(e).__name__}")
    
    print("\n" + "=" * 60)
    print("Enhanced analysis test completed!")

if __name__ == "__main__":
    test_enhanced_analysis()