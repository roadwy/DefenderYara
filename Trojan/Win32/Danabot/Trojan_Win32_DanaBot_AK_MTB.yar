
rule Trojan_Win32_DanaBot_AK_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d3 c1 ea 90 01 01 03 95 90 01 04 89 95 90 02 25 31 85 90 01 04 2b bd 90 02 25 29 85 90 01 04 ff 8d 90 02 25 8b 85 90 01 04 8b 4d 90 01 01 89 38 90 02 20 89 58 90 01 01 33 cd 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}