
rule TrojanDownloader_BAT_AsyncRAT_BB_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {51 00 7a 00 70 00 63 00 56 00 58 00 4e 00 6c 00 63 00 6e 00 4e 00 63 00 } //2 QzpcVXNlcnNc
		$a_01_1 = {58 00 45 00 46 00 77 00 63 00 45 00 52 00 68 00 64 00 47 00 46 00 63 00 54 00 47 00 39 00 6a 00 59 00 57 00 78 00 63 00 56 00 47 00 56 00 74 00 63 00 46 00 78 00 } //2 XEFwcERhdGFcTG9jYWxcVGVtcFx
		$a_01_2 = {55 00 30 00 39 00 47 00 56 00 46 00 64 00 42 00 55 00 6b 00 56 00 63 00 54 00 57 00 6c 00 6a 00 63 00 6d 00 39 00 7a 00 62 00 32 00 5a 00 30 00 58 00 46 00 64 00 70 00 62 00 6d 00 52 00 76 00 64 00 33 00 4e 00 63 00 51 00 33 00 56 00 79 00 63 00 6d 00 56 00 75 00 64 00 46 00 5a 00 6c 00 63 00 6e 00 4e 00 70 00 62 00 32 00 35 00 63 00 55 00 6e 00 56 00 75 00 } //2 U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu
		$a_01_3 = {55 00 33 00 6c 00 7a 00 64 00 47 00 56 00 74 00 49 00 45 00 31 00 6c 00 63 00 33 00 4e 00 68 00 5a 00 32 00 55 00 3d 00 } //2 U3lzdGVtIE1lc3NhZ2U=
		$a_01_4 = {54 00 47 00 56 00 6e 00 61 00 58 00 52 00 42 00 63 00 48 00 41 00 } //2 TGVnaXRBcHA
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}