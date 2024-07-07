
rule Trojan_Win32_Qbot_VDSK_MTB{
	meta:
		description = "Trojan:Win32/Qbot.VDSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 44 24 17 34 ff 88 44 24 6b 8a 44 24 3b 8b 4c 24 50 81 f1 9c 28 06 2f 88 44 24 4f 39 4c 24 30 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}