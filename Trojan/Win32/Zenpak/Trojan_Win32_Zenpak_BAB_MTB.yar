
rule Trojan_Win32_Zenpak_BAB_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 c8 03 45 f0 89 45 f0 8b 45 ec 83 c0 01 89 45 ec eb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}