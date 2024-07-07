
rule Trojan_Win32_Gepys_GZY_MTB{
	meta:
		description = "Trojan:Win32/Gepys.GZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 d3 ff 59 12 36 30 5d 8b c9 5e 5a 59 5b c3 53 51 52 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}