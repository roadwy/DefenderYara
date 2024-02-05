
rule Ransom_Win32_Exxroute_A{
	meta:
		description = "Ransom:Win32/Exxroute.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 01 00 "
		
	strings :
		$a_80_0 = {5f 57 41 4c 4c 45 54 00 } //_WALLET  01 00 
		$a_80_1 = {2e 63 72 79 70 74 00 } //.crypt  01 00 
		$a_80_2 = {64 65 5f 63 72 79 70 74 5f 72 65 61 64 6d 65 00 } //de_crypt_readme  01 00 
		$a_80_3 = {21 21 21 20 53 70 65 63 69 61 6c 6c 79 20 66 6f 72 20 79 6f 75 72 20 50 43 20 77 61 73 20 67 65 6e 65 72 61 74 65 64 20 70 65 72 73 6f 6e 61 6c 20 52 53 41 34 30 39 36 20 4b 65 79 20 2c 20 62 6f 74 68 20 70 75 62 6c 69 63 20 61 6e 64 20 70 72 69 76 61 74 65 2e } //!!! Specially for your PC was generated personal RSA4096 Key , both public and private.  01 00 
		$a_80_4 = {20 53 6f 20 2c 20 74 68 65 72 65 20 61 72 65 20 74 77 6f 20 77 61 79 73 20 79 6f 75 20 63 61 6e 20 63 68 6f 6f 73 65 3a 20 77 61 69 74 20 66 6f 72 20 61 20 6d 69 72 61 63 6c 65 20 61 6e 64 20 67 65 74 20 79 6f 75 72 20 70 72 69 63 65 20 64 6f 75 62 6c 65 64 2c 20 6f 72 20 73 74 61 72 74 20 6f 62 74 61 69 6e 69 6e 67 20 42 49 54 43 4f 49 4e 20 4e 4f 57 21 } // So , there are two ways you can choose: wait for a miracle and get your price doubled, or start obtaining BITCOIN NOW!  02 00 
		$a_80_5 = {5c 43 72 79 70 74 50 72 6f 6a 65 63 74 58 58 58 5c 4c 6f 61 64 65 72 5c 44 44 65 74 6f 75 72 73 2e 70 61 73 00 } //\CryptProjectXXX\Loader\DDetours.pas  02 00 
		$a_80_6 = {5c 43 72 79 70 74 50 72 6f 6a 65 63 74 58 58 58 5c 4c 6f 61 64 65 72 5c 49 6e 73 74 44 65 63 6f 64 65 2e 70 61 73 00 } //\CryptProjectXXX\Loader\InstDecode.pas  01 00 
		$a_80_7 = {3a 34 34 33 20 48 54 54 50 00 } //:443 HTTP  00 00 
		$a_00_8 = {7e 15 } //00 00 
	condition:
		any of ($a_*)
 
}