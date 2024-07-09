
rule Trojan_Win32_DiskFill_GZY_MTB{
	meta:
		description = "Trojan:Win32/DiskFill.GZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {a4 0b 13 7e ?? f9 32 af ?? ?? ?? ?? 8b c1 82 22 f5 55 25 } //5
		$a_01_1 = {34 4d 4b 52 a8 6f 72 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}