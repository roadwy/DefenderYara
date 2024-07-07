
rule TrojanDownloader_Win32_Bancos_AN{
	meta:
		description = "TrojanDownloader:Win32/Bancos.AN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 54 32 ff 59 2a d1 f6 d2 e8 90 01 04 8b 55 f0 8d 45 f4 e8 90 01 04 46 4b 75 da 90 00 } //1
		$a_01_1 = {6e 74 6c 64 6c 6c 2e 64 6c 6c 00 46 69 42 61 73 65 53 69 73 74 65 6d 61 00 46 75 6e 63 43 61 43 6c 69 65 6e 74 65 00 46 75 6e 63 52 65 6c 61 74 6f 72 69 6f 00 4d 6f 76 65 47 61 74 65 00 53 68 6f 77 46 6f 72 6d } //1 瑮摬汬搮汬䘀䉩獡卥獩整慭䘀湵䍣䍡楬湥整䘀湵剣汥瑡牯潩䴀癯䝥瑡e桓睯潆浲
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}