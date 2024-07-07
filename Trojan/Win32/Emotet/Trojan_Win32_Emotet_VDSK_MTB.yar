
rule Trojan_Win32_Emotet_VDSK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.VDSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d cc 8a 0c 31 32 08 88 0c 33 8b 5d d0 46 3b 75 1c 72 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}