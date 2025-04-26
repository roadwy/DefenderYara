
rule Trojan_Win32_Vidar_AXBA_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AXBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 8b 44 24 ?? 83 c4 08 8a 4c 2c ?? 30 0c 03 8b ce e8 ?? ?? ?? ?? 8b 6c 24 ?? 43 3b 5f ?? 0f 8c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}