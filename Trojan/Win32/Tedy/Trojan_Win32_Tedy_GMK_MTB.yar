
rule Trojan_Win32_Tedy_GMK_MTB{
	meta:
		description = "Trojan:Win32/Tedy.GMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {54 53 41 69 64 65 2e 73 74 61 74 } //TSAide.stat  01 00 
		$a_80_1 = {76 65 72 2e 6f 75 72 77 67 2e 63 6f 6d 2e 74 77 } //ver.ourwg.com.tw  01 00 
		$a_80_2 = {68 72 42 4b 55 45 41 48 32 39 34 37 31 43 } //hrBKUEAH29471C  01 00 
		$a_80_3 = {52 53 41 20 65 6e 63 72 79 70 74 20 65 72 72 6f 72 20 3a 25 64 } //RSA encrypt error :%d  01 00 
		$a_80_4 = {68 72 6a 69 79 6a 6a 37 } //hrjiyjj7  01 00 
		$a_01_5 = {40 2e 76 6d 70 30 } //01 00  @.vmp0
		$a_80_6 = {5a 6f 64 69 61 63 41 69 64 65 2e 65 78 65 } //ZodiacAide.exe  00 00 
	condition:
		any of ($a_*)
 
}