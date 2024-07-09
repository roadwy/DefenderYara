
rule Trojan_Win64_Xmrig_AX_MTB{
	meta:
		description = "Trojan:Win64/Xmrig.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {b5 31 d9 88 99 b0 b7 6f 79 ?? ?? dd 3f f9 ad d0 c4 86 14 8e 9e 07 ?? ?? e7 3b d6 f6 01 85 f5 3c 0d dc 57 9f 10 b9 19 ed 41 52 1e db b2 4d 07 21 30 b5 e2 bf fe 80 2a ac c1 cd 08 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}