
rule Trojan_Win32_Vidar_NEAD_MTB{
	meta:
		description = "Trojan:Win32/Vidar.NEAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c1 41 81 f9 ff 00 00 00 7c f5 32 c2 34 0f 88 04 1e 46 3b 75 0c } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}