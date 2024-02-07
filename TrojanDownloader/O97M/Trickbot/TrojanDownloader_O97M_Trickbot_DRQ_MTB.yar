
rule TrojanDownloader_O97M_Trickbot_DRQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Trickbot.DRQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 72 65 6e 65 67 6c 61 64 73 74 65 69 6e 6d 64 2e 73 6d 61 72 74 77 65 62 73 69 74 65 64 65 73 69 67 6e 2e 63 6f 6d 2f 6f 6c 61 6d 61 6e 73 72 77 2f 61 73 65 73 78 2e 70 6e 67 } //01 00  irenegladsteinmd.smartwebsitedesign.com/olamansrw/asesx.png
		$a_01_1 = {4c 4f 50 53 2e 4e 4e 49 49 4b 4b } //00 00  LOPS.NNIIKK
	condition:
		any of ($a_*)
 
}