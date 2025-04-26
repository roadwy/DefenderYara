
rule Trojan_Win64_PurelogStealer_AW_MTB{
	meta:
		description = "Trojan:Win64/PurelogStealer.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 6f 63 75 73 74 61 73 6b 2e 65 78 65 } //1 focustask.exe
		$a_01_1 = {77 65 78 74 72 61 63 74 2e 70 64 62 } //1 wextract.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}