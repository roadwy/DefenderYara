
rule Trojan_Win32_Lokibot_MRVU_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.MRVU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {23 38 3e 23 b2 30 99 38 3e 23 38 b2 30 a1 38 1c 16 07 b2 30 ad 1a 06 1a 13 b2 30 a9 01 55 3d 03 b2 30 b1 23 38 02 14 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}