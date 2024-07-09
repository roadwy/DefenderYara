
rule Trojan_Win64_XMRig_CCAN_MTB{
	meta:
		description = "Trojan:Win64/XMRig.CCAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 d0 48 98 48 8d 15 ?? ?? ?? ?? 40 32 2c 02 41 88 2c 3c 48 83 c7 01 49 39 fd 0f 84 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}