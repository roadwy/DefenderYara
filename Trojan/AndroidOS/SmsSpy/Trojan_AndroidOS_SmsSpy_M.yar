
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