
rule Trojan_Win64_R77Rootkit_CCIL_MTB{
	meta:
		description = "Trojan:Win64/R77Rootkit.CCIL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 44 03 d0 c1 ca ?? 41 80 39 61 8d 41 e0 0f 4c c1 03 d0 49 ff c1 66 45 85 d2 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}