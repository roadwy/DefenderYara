
rule Trojan_Win32_LummaStealer_PGLV_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PGLV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {3c 4e 6f 6e 65 3e 00 00 3c 4e 6f 6e 65 3e 00 00 00 00 00 00 63 6d 64 20 2f 76 20 2f 63 20 53 65 74 20 ?? ?? ?? ?? 3d 63 6d 64 20 26 20 21 ?? ?? ?? ?? 21 20 3c 20 [0-1f] 73 63 2e 65 78 65 20 2f 3f 6a 68 64 66 79 37 33 37 38 37 34 32 39 38 33 75 6b 72 6a 73 64 [0-ff] 3c 4e 6f 6e 65 3e 00 00 3c 4e 6f 6e 65 3e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}