
rule Trojan_Win32_Xploder_GNE_MTB{
	meta:
		description = "Trojan:Win32/Xploder.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {1b f2 30 66 ?? 4a 5d 20 23 } //5
		$a_03_1 = {10 1e 95 0d ?? ?? ?? ?? e4 ?? 51 d0 55 ?? 30 3f } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}