
rule Trojan_Win64_CryptInject_AA_MSR{
	meta:
		description = "Trojan:Win64/CryptInject.AA!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 70 43 30 35 2f 77 44 33 5f 3d 67 78 68 42 40 58 32 4d 66 37 40 2e 70 64 62 } //1 0pC05/wD3_=gxhB@X2Mf7@.pdb
	condition:
		((#a_01_0  & 1)*1) >=1
 
}