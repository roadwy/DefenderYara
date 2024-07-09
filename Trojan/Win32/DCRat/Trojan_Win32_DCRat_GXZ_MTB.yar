
rule Trojan_Win32_DCRat_GXZ_MTB{
	meta:
		description = "Trojan:Win32/DCRat.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 c0 03 dd 8b 6c 24 ?? 13 d0 0f ac d3 ?? 8b d1 6b c3 ?? 2b d0 8a 82 ?? ?? ?? ?? 30 81 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}