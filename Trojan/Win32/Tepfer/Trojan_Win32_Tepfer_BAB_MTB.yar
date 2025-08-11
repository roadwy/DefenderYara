
rule Trojan_Win32_Tepfer_BAB_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 8b 55 ec 01 13 8b 75 d4 03 75 ac 03 75 ec 03 f0 bf 89 15 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}