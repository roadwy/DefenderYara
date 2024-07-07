
rule Ransom_Linux_CerberRansom_A{
	meta:
		description = "Ransom:Linux/CerberRansom.A,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {24 49 6e 66 6f 3a 20 54 68 69 73 20 66 69 6c 65 20 69 73 20 70 61 63 6b 65 64 20 77 69 74 68 20 74 68 65 20 55 50 58 20 65 78 65 63 75 74 61 62 6c 65 20 70 61 63 6b 65 72 20 68 74 74 70 3a 2f 2f 75 70 78 2e 73 66 2e 6e 65 74 20 24 } //$Info: This file is packed with the UPX executable packer http://upx.sf.net $  1
		$a_80_1 = {24 49 64 3a 20 55 50 58 20 33 2e 39 36 20 43 6f 70 79 72 69 67 68 74 20 28 43 29 20 31 39 39 36 2d 32 30 32 30 20 74 68 65 20 55 50 58 20 54 65 61 6d 2e 20 41 6c 6c 20 52 69 67 68 74 73 20 52 65 73 65 72 76 65 64 2e 20 24 } //$Id: UPX 3.96 Copyright (C) 1996-2020 the UPX Team. All Rights Reserved. $  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}