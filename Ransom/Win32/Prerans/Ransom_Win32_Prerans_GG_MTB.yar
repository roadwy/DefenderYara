
rule Ransom_Win32_Prerans_GG_MTB{
	meta:
		description = "Ransom:Win32/Prerans.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0b 00 00 01 00 "
		
	strings :
		$a_80_0 = {65 6e 63 72 79 70 74 } //encrypt  01 00 
		$a_80_1 = {43 72 79 70 74 41 63 71 75 69 72 65 43 6f 6e 74 65 78 74 } //CryptAcquireContext  01 00 
		$a_80_2 = {44 65 63 72 79 70 74 69 6f 6e } //Decryption  01 00 
		$a_80_3 = {6e 65 74 20 73 74 6f 70 } //net stop  01 00 
		$a_80_4 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 6f 70 6d 6f 64 65 } //netsh firewall set opmode  01 00 
		$a_80_5 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c } //vssadmin delete shadows /all  01 00 
		$a_80_6 = {77 6d 69 63 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //wmic shadowcopy delete  01 00 
		$a_80_7 = {62 63 64 65 64 69 74 20 2f 73 65 74 } //bcdedit /set  01 00 
		$a_80_8 = {72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f } //recoveryenabled no  01 00 
		$a_80_9 = {62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 69 67 6e 6f 72 65 61 6c 6c 66 61 69 6c 75 72 65 73 } //bootstatuspolicy ignoreallfailures  01 00 
		$a_80_10 = {77 62 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 63 61 74 61 6c 6f 67 20 2d 71 75 69 65 74 } //wbadmin delete catalog -quiet  00 00 
	condition:
		any of ($a_*)
 
}