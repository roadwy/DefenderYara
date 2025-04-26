
rule TrojanDownloader_Win32_Grameyoon_A{
	meta:
		description = "TrojanDownloader:Win32/Grameyoon.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 6f 6d 6f 63 65 6c 6c 2e 63 6f 6d 2f 6c 6f 67 2f 69 6e 73 74 61 6c 6c 2e 70 68 70 3f 6d 61 63 3d 00 } //1 潭潭散汬挮浯氯杯椯獮慴汬瀮灨洿捡=
		$a_01_1 = {75 70 64 61 74 65 2e 6d 6f 6d 6f 63 65 6c 6c 2e 63 6f 6d 2f 64 77 6e 2f 6c 6f 67 69 6e 66 6f 00 } //1
		$a_01_2 = {41 4c 49 4d 20 61 67 65 6e 74 20 6d 61 6e 61 67 65 72 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}