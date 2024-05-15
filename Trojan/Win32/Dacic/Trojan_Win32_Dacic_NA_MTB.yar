
rule Trojan_Win32_Dacic_NA_MTB{
	meta:
		description = "Trojan:Win32/Dacic.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {01 d8 31 d8 c1 e0 03 c1 eb 02 90 80 2f 88 f6 2f 47 e2 de } //05 00 
		$a_81_1 = {5f 63 72 79 70 74 65 64 2e 64 6c 6c } //00 00  _crypted.dll
	condition:
		any of ($a_*)
 
}