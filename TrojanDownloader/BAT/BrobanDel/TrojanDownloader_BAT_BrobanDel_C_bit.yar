
rule TrojanDownloader_BAT_BrobanDel_C_bit{
	meta:
		description = "TrojanDownloader:BAT/BrobanDel.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 48 64 70 62 6d 78 76 5a 79 35 73 62 32 63 3d } //01 00  XHdpbmxvZy5sb2c=
		$a_01_1 = {55 30 39 47 56 46 64 42 55 6b 56 63 51 32 78 68 63 33 4e 6c 63 31 78 74 63 32 4e 6d 61 57 78 6c 58 48 4e 6f 5a 57 78 73 58 47 39 77 5a 57 35 63 59 32 39 74 62 57 46 75 5a 41 3d 3d } //01 00  U09GVFdBUkVcQ2xhc3Nlc1xtc2NmaWxlXHNoZWxsXG9wZW5cY29tbWFuZA==
		$a_01_2 = {55 30 39 47 56 46 64 42 55 6b 56 63 54 57 6c 6a 63 6d 39 7a 62 32 5a 30 58 46 64 70 62 6d 52 76 64 33 4e 63 51 33 56 79 63 6d 56 75 64 46 5a 6c 63 6e 4e 70 62 32 35 63 55 6e 56 75 } //01 00  U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu
		$a_01_3 = {54 57 6c 6a 62 33 4a 7a 62 32 5a 30 49 46 56 7a 5a 58 49 67 55 32 56 32 63 6d 6c 6a 5a 51 3d 3d } //01 00  TWljb3Jzb2Z0IFVzZXIgU2V2cmljZQ==
		$a_01_4 = {59 32 31 6b 49 43 39 6a 49 48 42 70 62 6d 63 67 4d 53 34 78 4c 6a 45 75 4d 53 41 74 62 69 41 78 49 43 31 33 49 44 4d 77 4d 44 41 67 50 69 42 4f 64 57 77 67 4a 69 42 45 5a 57 77 67 49 67 3d 3d } //01 00  Y21kIC9jIHBpbmcgMS4xLjEuMSAtbiAxIC13IDMwMDAgPiBOdWwgJiBEZWwgIg==
		$a_01_5 = {49 6a 70 61 62 32 35 6c 4c 6b 6c 6b 5a 57 35 30 61 57 5a 70 5a 58 49 69 } //00 00  Ijpab25lLklkZW50aWZpZXIi
	condition:
		any of ($a_*)
 
}