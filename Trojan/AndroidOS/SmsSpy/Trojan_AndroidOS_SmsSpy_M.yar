
rule Trojan_AndroidOS_SmsSpy_M{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.M,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {26 74 65 78 74 3d 42 65 72 68 61 73 69 6c 20 4b 69 72 69 6d 20 53 4d 53 20 6b 65 20 3a } //2 &text=Berhasil Kirim SMS ke :
		$a_01_1 = {2c 20 49 73 69 20 50 65 73 61 6e 20 3a } //2 , Isi Pesan :
		$a_01_2 = {36 32 38 31 33 38 33 31 31 35 37 37 36 } //2 6281383115776
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
rule Trojan_AndroidOS_SmsSpy_M_2{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.M,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {26 74 65 78 74 3d 2a 4b 65 6e 74 75 74 20 48 79 64 72 6f 20 43 6f 63 6f 20 2a 20 25 30 41 25 30 41 2a 4b 65 6e 74 75 74 2a } //2 &text=*Kentut Hydro Coco * %0A%0A*Kentut*
		$a_01_1 = {54 65 6c 65 70 6f 6e 20 48 79 64 72 6f 20 43 6f 63 6f } //2 Telepon Hydro Coco
		$a_01_2 = {61 70 70 6a 61 76 61 2f 52 65 63 65 69 76 65 53 6d 73 } //2 appjava/ReceiveSms
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}