
rule TrojanDownloader_O97M_Donoff_FE{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FE,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 64 69 6d 38 36 20 3d 20 64 69 6d 30 34 28 64 69 6d 33 30 2c 20 64 69 6d 35 33 28 64 69 6d 34 30 28 64 69 6d 38 28 29 2c 20 64 69 6d 31 36 28 29 2c 20 33 29 2c 20 33 29 2c 20 31 2c 20 30 } //1 Set dim86 = dim04(dim30, dim53(dim40(dim8(), dim16(), 3), 3), 1, 0
		$a_01_1 = {64 69 6d 36 36 28 64 69 6d 33 29 20 3d 20 64 69 6d 35 39 28 64 69 6d 36 36 28 64 69 6d 33 29 2c 20 28 64 69 6d 31 36 28 64 69 6d 39 38 28 28 64 69 6d 31 36 28 64 69 6d 35 31 29 20 2b 20 64 69 6d 31 36 28 64 69 6d 38 37 29 29 2c 20 28 34 37 38 30 20 2d 20 34 35 32 34 29 29 29 29 29 } //1 dim66(dim3) = dim59(dim66(dim3), (dim16(dim98((dim16(dim51) + dim16(dim87)), (4780 - 4524)))))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}