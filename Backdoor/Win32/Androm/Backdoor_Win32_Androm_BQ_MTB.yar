
rule Backdoor_Win32_Androm_BQ_MTB{
	meta:
		description = "Backdoor:Win32/Androm.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 45 ff 0f b6 75 ff 8a 14 06 00 55 fe 0f b6 4d fe 8a 1c 01 88 1c 06 88 14 01 0f b6 0c 06 0f b6 d2 03 ca 8b 55 f4 81 e1 ff 00 00 00 8a 0c 01 32 0c 3a 88 0f 47 ff 4d f8 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}