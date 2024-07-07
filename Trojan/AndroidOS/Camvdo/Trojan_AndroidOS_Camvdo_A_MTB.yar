
rule Trojan_AndroidOS_Camvdo_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Camvdo.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 63 68 61 67 61 6c 6c 2e 73 63 72 65 65 6e 73 68 6f 74 } //1 com.chagall.screenshot
		$a_00_1 = {63 6f 6d 2e 63 68 61 67 61 6c 6c 2e 47 50 53 5f 64 61 74 61 } //1 com.chagall.GPS_data
		$a_00_2 = {63 61 6d 76 64 6f 3d 63 61 6d 76 64 6f } //2 camvdo=camvdo
		$a_00_3 = {3e 73 6d 73 4d 6f 6e 69 74 65 72 3d } //1 >smsMoniter=
		$a_00_4 = {63 61 6c 6c 4d 6f 6e 69 74 65 72 } //1 callMoniter
		$a_00_5 = {31 37 33 2e 32 34 39 2e 35 30 2e 33 34 2d 73 68 61 72 65 62 6f 78 73 2e 6e 65 74 } //1 173.249.50.34-shareboxs.net
		$a_00_6 = {2f 2e 5f 48 41 41 54 4e 45 43 53 } //1 /._HAATNECS
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}