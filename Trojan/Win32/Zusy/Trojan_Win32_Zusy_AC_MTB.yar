
rule Trojan_Win32_Zusy_AC_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e6 04 2b f1 03 b5 90 01 02 ff ff 52 03 f6 0f af de 03 9d 90 01 02 ff ff 51 32 c3 88 85 90 00 } //01 00 
		$a_01_1 = {54 0e 46 bf 0e 66 74 53 4b 5c f6 06 67 48 6a 3e 0a 72 70 64 4a 47 66 50 a6 } //00 00 
	condition:
		any of ($a_*)
 
}