
rule Trojan_Win32_Tavdig_Crypt_dha{
	meta:
		description = "Trojan:Win32/Tavdig.Crypt!dha,SIGNATURE_TYPE_PEHSTR_EXT,ffffff90 01 ffffff90 01 04 00 00 "
		
	strings :
		$a_01_0 = {45 78 65 63 75 74 65 50 61 74 63 68 } //100 ExecutePatch
		$a_01_1 = {4d 61 69 6e 40 31 32 } //100 Main@12
		$a_01_2 = {4d 61 6b 65 55 75 69 64 } //100 MakeUuid
		$a_01_3 = {6b 41 69 43 6f 64 65 } //100 kAiCode
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100) >=400
 
}