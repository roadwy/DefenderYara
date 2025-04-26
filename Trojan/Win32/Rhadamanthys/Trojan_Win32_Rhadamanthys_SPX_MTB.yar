
rule Trojan_Win32_Rhadamanthys_SPX_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.SPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c8 c7 05 ?? ?? ?? ?? ee 3d ea f4 8b 45 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}