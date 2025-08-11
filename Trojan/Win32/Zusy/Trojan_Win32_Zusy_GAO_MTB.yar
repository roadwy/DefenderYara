
rule Trojan_Win32_Zusy_GAO_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 03 45 0c 8b 55 f8 03 55 08 8a 12 32 55 ff 88 10 ff 45 f8 fe 45 ff } //8
		$a_01_1 = {44 45 41 44 42 41 42 45 } //2 DEADBABE
	condition:
		((#a_01_0  & 1)*8+(#a_01_1  & 1)*2) >=10
 
}