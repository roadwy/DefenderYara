
rule Trojan_BAT_Nanocore_RDA_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {35 64 31 30 37 33 37 36 2d 30 33 33 62 2d 34 61 66 34 2d 61 34 31 33 2d 37 31 31 34 63 64 65 39 32 66 62 33 } //1 5d107376-033b-4af4-a413-7114cde92fb3
		$a_01_1 = {6e 00 6d 00 35 00 65 00 62 00 78 00 30 00 79 00 64 00 7a 00 71 00 } //1 nm5ebx0ydzq
		$a_01_2 = {43 6f 6e 74 72 6f 6c 69 6f 73 } //1 Controlios
		$a_01_3 = {2d 2d 51 64 6a 24 3b 61 3a 39 70 44 73 62 40 20 3d 7d 20 6b 7c 75 39 67 5c 26 2e } //1 --Qdj$;a:9pDsb@ =} k|u9g\&.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}