
rule Trojan_Win32_Tepfer_BA_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c7 31 03 83 45 ec 04 83 c3 04 8b 45 ec 3b 45 dc 72 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}