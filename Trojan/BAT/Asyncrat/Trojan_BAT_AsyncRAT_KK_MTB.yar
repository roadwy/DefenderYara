
rule Trojan_BAT_AsyncRAT_KK_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {20 e8 03 00 00 28 22 00 00 0a fe 0c 00 00 20 01 00 00 00 58 fe 0e 00 00 fe 0c 00 00 7e 1b 00 00 04 28 23 00 00 0a 3f d5 ff ff ff } //5
		$a_81_1 = {43 3a 50 53 4b 4c 41 50 5c 57 69 6e 64 6f 77 50 53 4b 4c 41 50 73 5c 53 79 73 74 65 6d 33 32 5c 75 50 53 4b 4c 41 50 73 65 72 69 6e 69 74 50 53 4b 4c 41 50 2e 65 78 65 2c } //20 C:PSKLAP\WindowPSKLAPs\System32\uPSKLAPserinitPSKLAP.exe,
		$a_81_2 = {6f 67 6d 46 74 77 61 72 65 5c 43 67 6d 4c 61 53 67 6d 53 65 67 6d 73 5c 6d 53 67 6d 2d 73 45 74 67 6d 54 69 6e 47 73 67 6d 5c 53 48 67 6d 65 6c 6c 5c 4f 50 67 6d 65 6e 5c 63 6f 4d 4d 67 6d 61 6e 64 } //10 ogmFtware\CgmLaSgmSegms\mSgm-sEtgmTinGsgm\SHgmell\OPgmen\coMMgmand
	condition:
		((#a_01_0  & 1)*5+(#a_81_1  & 1)*20+(#a_81_2  & 1)*10) >=35
 
}