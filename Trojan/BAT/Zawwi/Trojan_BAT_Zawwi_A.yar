
rule Trojan_BAT_Zawwi_A{
	meta:
		description = "Trojan:BAT/Zawwi.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 45 74 46 57 56 39 44 56 56 4a 53 52 55 35 55 58 31 56 54 52 56 4a 63 55 32 39 6d 64 48 64 68 63 6d 56 63 54 57 6c 6a 63 6d 39 7a 62 32 5a 30 58 46 64 70 62 6d 52 76 64 33 4d 67 54 6c 52 63 51 33 56 79 63 6d 56 75 64 46 5a 6c 63 6e 4e 70 62 32 35 63 56 32 6c 75 5a 47 39 33 63 77 3d 3d } //1 SEtFWV9DVVJSRU5UX1VTRVJcU29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3MgTlRcQ3VycmVudFZlcnNpb25cV2luZG93cw==
		$a_01_1 = {54 47 39 68 5a 41 3d 3d } //1 TG9hZA==
		$a_01_2 = {59 32 31 6b 49 43 39 6a 49 41 3d 3d } //1 Y21kIC9jIA==
		$a_01_3 = {77 69 7a 7a 61 2e 65 78 65 } //1 wizza.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}