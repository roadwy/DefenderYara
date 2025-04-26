
rule Trojan_Win32_Redline_GHA_MTB{
	meta:
		description = "Trojan:Win32/Redline.GHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 0e 8b c6 83 e0 03 ba ?? ?? ?? ?? 8a 80 ?? ?? ?? ?? 32 c3 02 c3 88 04 0e } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}