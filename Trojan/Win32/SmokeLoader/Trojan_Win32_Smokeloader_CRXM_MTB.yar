
rule Trojan_Win32_Smokeloader_CRXM_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.CRXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c1 8d 0c 2f 33 c1 2b f0 8b d6 c1 e2 } //1
		$a_03_1 = {33 cb 33 c1 2b f8 a1 ?? ?? ?? ?? 3d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}