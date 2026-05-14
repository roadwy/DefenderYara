
rule Trojan_Win32_Doina_PGX_MTB{
	meta:
		description = "Trojan:Win32/Doina.PGX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_81_0 = {52 4e 45 53 56 40 51 44 5b 4c 68 62 71 6e 72 6e 65 73 5b 56 68 6d 63 6e 76 72 5b 42 74 71 71 64 6d 73 55 64 71 72 68 6e 6d 5b 44 77 6f 6b 6e 71 64 71 5b 40 63 75 60 6d 62 64 63 5b 45 6e 6b 63 64 71 5b 47 68 63 64 45 68 6b 64 44 77 73 } //2 RNESV@QD[Lhbqnrnes[Vhmcnvr[BtqqdmsUdqrhnm[Dwoknqdq[@cu`mbdc[Enkcdq[GhcdEhkdDws
		$a_81_1 = {4c 6f 63 61 6c 69 7a 65 64 52 65 73 6f 75 72 63 65 4e 61 6d 65 3d 40 73 68 65 6c 6c 33 32 2e 64 6c 6c 2c 2d 33 30 34 38 31 } //1 LocalizedResourceName=@shell32.dll,-30481
		$a_81_2 = {52 58 52 53 44 4c 5b 42 6e 6d 73 71 6e 6b 52 64 73 2f 2f 30 5b 42 6e 6d 73 71 6e 6b 5b 52 60 65 64 41 6e 6e 73 } //2 RXRSDL[BnmsqnkRds//0[Bnmsqnk[R`edAnns
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*2) >=5
 
}