
rule Trojan_Win32_FareIt_HGFT_MTB{
	meta:
		description = "Trojan:Win32/FareIt.HGFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c7 0f ef d3 66 0f fc fe 0f 64 cd 0f fd e3 0f 71 f7 db 66 0f fc f2 f3 a4 66 0f dc cd 0f f9 d4 fc 0f fa e5 66 0f e1 cb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}