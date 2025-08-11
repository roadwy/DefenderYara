
rule Trojan_Win32_Barys_PGA_MTB{
	meta:
		description = "Trojan:Win32/Barys.PGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 ec 89 45 ec 8b 4d 10 89 4d f0 ?? ?? 8b 55 f0 83 c2 ?? 89 55 f0 8b 45 10 05 ?? ?? ?? ?? 39 45 f0 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}