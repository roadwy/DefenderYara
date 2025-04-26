
rule Trojan_BAT_Redline_GEK_MTB{
	meta:
		description = "Trojan:BAT/Redline.GEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 06 72 4a 03 00 70 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 0b 07 02 16 02 8e 69 6f ?? ?? ?? 0a 0c 2b 00 08 2a } //10
		$a_80_1 = {38 66 4e 6b 6e 2f 74 56 66 45 68 2b 32 47 67 7a 68 6d 4a 70 38 30 43 58 43 65 69 54 4f 70 66 49 61 78 74 54 33 38 38 66 70 69 41 3d } //8fNkn/tVfEh+2GgzhmJp80CXCeiTOpfIaxtT388fpiA=  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}