
rule Trojan_Win32_Zenpak_ASG_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 1f 8b 55 ec 8b 5d d0 32 0c 1a 8b 55 e8 88 0c 1a } //1
		$a_01_1 = {01 df 89 f8 89 55 c8 99 f7 fe 89 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}