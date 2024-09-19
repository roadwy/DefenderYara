
rule Trojan_Win32_ClipBanker_CD_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {28 28 5b 31 33 5d 5b 61 2d 6b 6d 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 30 2d 39 5d 7b 32 36 2c 33 33 7d 2c 2a 29 7c 28 62 63 28 30 28 5b 61 63 2d 68 6a 2d 6e 70 2d 7a 30 32 2d 39 5d 7b 33 39 7d 7c 5b 61 63 2d 68 6a 2d 6e 70 2d 7a 30 32 2d 39 5d 7b 35 39 7d 29 7c 31 5b 61 63 2d 68 6a 2d 6e 70 2d 7a 30 32 2d 39 5d 7b 38 2c 38 37 7d 29 2c 2a 29 29 } //2 (([13][a-km-zA-HJ-NP-Z0-9]{26,33},*)|(bc(0([ac-hj-np-z02-9]{39}|[ac-hj-np-z02-9]{59})|1[ac-hj-np-z02-9]{8,87}),*))
		$a_01_1 = {54 5b 61 2d 7a 41 2d 5a 30 2d 39 5d 7b 33 33 7d } //2 T[a-zA-Z0-9]{33}
		$a_01_2 = {30 78 5b 61 2d 66 41 2d 46 30 2d 39 5d 7b 34 30 7d } //2 0x[a-fA-F0-9]{40}
		$a_01_3 = {43 6c 69 70 43 68 61 6e 67 65 64 20 5b 25 73 5d } //4 ClipChanged [%s]
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*4) >=10
 
}