
rule Trojan_Win32_Redline_GHP_MTB{
	meta:
		description = "Trojan:Win32/Redline.GHP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 01 8b 55 0c 03 55 dc 0f b6 02 83 f0 5a 8b 4d 0c 03 4d dc 88 01 8b 55 0c 03 55 dc 0f b6 02 35 ff 00 00 00 8b 4d 0c 03 4d dc 88 01 8b 55 0c 03 55 dc 0f b6 02 83 e8 10 8b 4d 0c 03 4d dc 88 01 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}