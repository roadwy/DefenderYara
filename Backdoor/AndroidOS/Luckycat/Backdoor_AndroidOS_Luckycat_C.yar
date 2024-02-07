
rule Backdoor_AndroidOS_Luckycat_C{
	meta:
		description = "Backdoor:AndroidOS/Luckycat.C,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6d 6f 6e 64 61 79 6e 65 77 73 2e 74 6b 2f 63 61 6d 2f 63 6d 2e 70 68 70 3f 76 3d } //01 00  http://mondaynews.tk/cam/cm.php?v=
		$a_01_1 = {26 63 68 6d 6f 64 20 2d 52 20 37 37 37 20 2f 64 61 74 61 2f 64 61 74 61 2f 63 6f 6d 2e 74 65 6e 63 65 6e 74 2e 6d 6d } //00 00  &chmod -R 777 /data/data/com.tencent.mm
	condition:
		any of ($a_*)
 
}