
rule Trojan_Win32_PonyStealer_GNK_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.GNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 0c fb ef be ?? ?? ?? ?? 49 32 0b 43 49 } //5
		$a_01_1 = {28 08 f0 00 00 34 d3 6b 0e dd eb } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}