
rule Trojan_Win32_NanoBot_RB_MTB{
	meta:
		description = "Trojan:Win32/NanoBot.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 4d f9 8a 4d fa 8a 55 fb 32 4d fe 32 55 ff 34 dd 88 45 f8 88 4d fa 88 55 fb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}