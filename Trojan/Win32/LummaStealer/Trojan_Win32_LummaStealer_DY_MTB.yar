
rule Trojan_Win32_LummaStealer_DY_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 ca c1 ea 1e 31 ca 69 ca ?? ?? ?? ?? 01 c1 41 8b 15 ?? ?? ?? ?? 89 4c 82 08 3d ?? ?? ?? ?? 74 ?? 89 ca c1 ea 1e 31 ca 69 ca ?? ?? ?? ?? 01 c1 83 c1 02 8b 15 ?? ?? ?? ?? 89 4c 82 0c 83 c0 02 eb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}