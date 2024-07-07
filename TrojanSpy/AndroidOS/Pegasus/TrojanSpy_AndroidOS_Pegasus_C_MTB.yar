
rule TrojanSpy_AndroidOS_Pegasus_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Pegasus.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 65 67 61 73 75 73 } //1 pegasus
		$a_00_1 = {65 78 70 6f 72 74 20 4c 44 5f 4c 49 42 52 41 52 59 5f 50 41 54 48 3d 2f 76 65 6e 64 6f 72 2f 6c 69 62 3a 2f 73 79 73 74 65 6d 2f 6c 69 62 3b 20 63 68 6d 6f 64 20 37 37 37 20 2f 64 61 74 61 2f 64 61 74 61 2f 63 6f 6d 2e 77 68 61 74 73 61 70 70 2f 64 61 74 61 62 61 73 65 73 2f } //2 export LD_LIBRARY_PATH=/vendor/lib:/system/lib; chmod 777 /data/data/com.whatsapp/databases/
		$a_00_2 = {2f 73 79 73 74 65 6d 2f 63 73 6b } //2 /system/csk
		$a_00_3 = {42 69 6e 61 72 79 20 53 6d 73 20 4d 6f 6e 69 74 6f 72 } //1 Binary Sms Monitor
		$a_00_4 = {63 68 6d 6f 64 4f 6e 65 43 6f 6d 6d 61 6e 64 } //1 chmodOneCommand
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=6
 
}