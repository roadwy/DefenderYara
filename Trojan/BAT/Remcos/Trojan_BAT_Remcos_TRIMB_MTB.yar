
rule Trojan_BAT_Remcos_TRIMB_MTB{
	meta:
		description = "Trojan:BAT/Remcos.TRIMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,33 00 33 00 08 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 4d 65 74 68 6f 64 } //10 GetMethod
		$a_01_1 = {52 65 70 6c 61 63 65 } //10 Replace
		$a_01_2 = {49 6e 76 6f 6b 65 } //10 Invoke
		$a_01_3 = {52 65 76 65 72 73 65 } //10 Reverse
		$a_01_4 = {54 6f 41 72 72 61 79 } //10 ToArray
		$a_80_5 = {68 74 74 70 3a 2f 2f 74 72 69 65 74 6c 6f 6e 67 76 69 6e 68 76 69 65 6e 2e 69 6e 66 6f 2f 2e 74 6d 62 2f } //http://trietlongvinhvien.info/.tmb/  1
		$a_80_6 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 75 70 6c 6f 6f 64 65 72 2e 6e 65 74 2f 69 6d 67 2f 69 6d 61 67 65 2f 34 30 2f 65 33 36 62 65 62 64 32 32 32 36 30 63 30 33 66 33 61 34 30 62 36 33 34 38 39 37 36 66 61 35 62 2f 57 4d 49 2d 50 72 6f 76 69 64 65 72 2d 48 6f 73 74 2e 6a 70 67 } //https://www.uplooder.net/img/image/40/e36bebd22260c03f3a40b6348976fa5b/WMI-Provider-Host.jpg  1
		$a_80_7 = {68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 39 33 32 34 31 33 34 35 39 38 37 32 37 34 37 35 34 34 2f 39 33 33 30 39 38 38 39 33 30 31 39 38 36 31 30 34 32 2f 4a 64 6e 70 61 6e 6b 69 2e 62 69 6e } //https://cdn.discordapp.com/attachments/932413459872747544/933098893019861042/Jdnpanki.bin  1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=51
 
}